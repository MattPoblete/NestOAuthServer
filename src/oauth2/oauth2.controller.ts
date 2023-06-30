import {
  Controller,
  Post,
  Request,
  Get,
  Body,
  Query,
  Headers,
  BadRequestException,
  NotFoundException,
  Res,
  Param,
} from '@nestjs/common';
import { UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { scopeGuard } from './guards/OAuthJwt.guard';
import { scopeProtected } from './decorators/scope-protected.decorator';
import { Oauth2Service } from './oauth2.service';
import { scopes } from './interfaces';
import { Public } from './decorators/public.decorator';
//eslint-disable-next-line
import { createOAuthClient } from './dto/OAuthClient.dto';
import { ApiKeyGuard } from './guards/apiKey.guard';
import { createToken } from './dto/CreateToken.dto';
import { OAuthClient } from './entities/OAuthClient.entity';

@Controller('OAuth')
export class Oauth2Controller {
  constructor(
    private readonly oauth2Service: Oauth2Service,
    private readonly config: ConfigService,
  ) {}
  private issuerURL = this.config.get('oauthIssuer');

  @UseGuards(ApiKeyGuard)
  @Get('client/:id')
  async getClientData(@Param('id') id) {
    const client = (await this.oauth2Service.getClient(id)) as OAuthClient;
    const data = {
      client_name: client.name,
      client_logo: client.logo,
      client_tos: client.tos,
    };
    return data;
  }

  @UseGuards(ApiKeyGuard)
  @Post('createClient')
  async createClient(@Body() createOAuthClient: createOAuthClient) {
    const newClient = await this.oauth2Service.createClient(createOAuthClient);
    return newClient;
  }

  @Get('/.well-known/openid-configuration')
  discover() {
    const oidConfig = {
      issuer: this.issuerURL,
      authorization_endpoint: `${this.issuerURL}/authorize`,
      token_endpoint: `${this.issuerURL}/token`,
      userinfo_endpoint: `${this.issuerURL}/userinfo`,
      scopes_supported: ['profile'],
      response_types_supported: ['code', 'token'],
      id_token_signing_alg_values_supported: ['RS256'],
      token_endpoint_auth_methods_supported: [
        'client_secret_basic',
        'client_secret_post',
      ],
    };
    return oidConfig;
  }

  @Get('isauth')
  async isauth(
    @Request() req,
    @Query('response_type') responseType: string,
    @Query('client_id') clientId: string,
    @Query('redirect_uri') redirectUri: string,
    @Query('scope') scope: string,
  ) {
    const rawToken = req.headers.authorization;
    if (!rawToken) throw new BadRequestException('user token not detected');
    const userToken = rawToken.split(' ')[1];
    const user = await this.oauth2Service.getUserFromUserToken(userToken);
    const payload = {
      responseType,
      clientId,
      redirectUri,
      scope,
      userToken,
    };
    const validateAuth = await this.oauth2Service.isAuthorized(user, payload);
    return validateAuth;
  }

  @Get('authorize')
  async authorize(
    @Request() req,
    @Query('response_type') responseType: string,
    @Query('client_id') clientId: string,
    @Query('redirect_uri') redirectUri: string,
    @Query('scope') scope: string,
  ) {
    if (responseType !== 'code') {
      throw new BadRequestException('');
    }
    const client = await this.oauth2Service.validateAuthorizationRequest(
      clientId,
      redirectUri,
      scope,
    );
    const rawToken = req.headers.authorization;
    if (!rawToken) throw new BadRequestException('user token not detected');
    const userToken = rawToken.split(' ')[1];
    const user = await this.oauth2Service.getUserFromUserToken(userToken);
    if (!user) throw new NotFoundException('User not found');
    const authorizationCode =
      await this.oauth2Service.generateAuthorizationCode(
        client,
        user,
        scope,
        redirectUri,
      );
    return {
      url: `${redirectUri}?code=${authorizationCode}`,
      statusCode: 200,
    };
  }

  @Public()
  @Post('token')
  async getToken(@Res() response, @Body() credentialsToken: createToken) {
    const req = credentialsToken;
    if (req.grant_type != 'authorization_code')
      throw new BadRequestException('grant_type not supported');
    //const client = await this.oauth2Service.getClient(client_id);
    const isValidClient = await this.oauth2Service.validateClient(
      req.client_id,
      req.client_secret,
    );
    await this.oauth2Service.validateURI(isValidClient, req.redirect_uri);
    const { user, scope } = await this.oauth2Service.getUserFromCode(req.code);
    const token = await this.oauth2Service.generateAccessToken(
      isValidClient,
      user,
      scope,
      req.code,
    );
    await this.oauth2Service.saveToken(
      token,
      isValidClient,
      user,
      scope,
      req.code,
    );
    return response.status(200).send(token);
  }

  @UseGuards(AuthGuard('OAuthJwt'), scopeGuard)
  @scopeProtected(scopes.profile)
  @Get('userinfo')
  async getUserInfo(@Headers('Authorization') authorization: string) {
    const accessToken = authorization.replace('Bearer ', '');
    const user_id = (await this.oauth2Service.getUserFromToken(accessToken))
      .user_id;
    const user = await this.oauth2Service.getUserInfo(user_id);
    return user;
  }

  @Post('revokeAccessToken')
  async revokeAccessToken(@Request() req) {
    const token = req.headers.authorization.split(' ')[1];
    return this.oauth2Service.revokeAcessToken(token);
  }
}
