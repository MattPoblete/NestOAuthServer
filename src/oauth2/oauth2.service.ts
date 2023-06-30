import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import {
  UnauthorizedClientError,
  UnauthorizedRequestError,
} from 'oauth2-server';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import axios from 'axios';

import {
  scopes,
  tokenPayload,
  userInfo,
  patient,
  userToken,
} from './interfaces';
import { OAuthClient } from './entities/OAuthClient.entity';
import { OAuthUser } from './entities/OAuthUser.entity';
import { OAuthToken } from './entities/OAuthToken.entity';
import { OAuthAuthorizationCode } from './entities/OAuthAuthorizationCode.entity';
import { createOAuthClient } from './dto/OAuthClient.dto';

@Injectable()
export class Oauth2Service {
  constructor(
    //eslint-disable-next-line
    @InjectModel('OAuthClient')
    private readonly oauthClient: Model<OAuthClient>,
    @InjectModel('OAuthUser') private readonly oauthUser: Model<OAuthUser>,
    @InjectModel('OAuthToken') private readonly oauthToken: Model<OAuthToken>,
    @InjectModel('OAuthAuthorizationCode')
    private readonly oauthAuthorizationCode: Model<OAuthAuthorizationCode>,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
  ) {}

  //time common
  //time expressed in seconds
  accessTokenExpTime = 7200; //def 7200  (s)[2h]
  authCodeExpTime = 3600; //def 3600  (s)[1h]

  //today's date in UT format (seconds since 1/1/1970)
  getUT() {
    const currentDate = new Date();
    const UT = Math.floor(currentDate.getTime() / 1000);
    return UT;
  }

  //getApiCoreURL
  apiCoreURL() {
    const url = this.config.get('apiCore');
    return url;
  }

  //Oauth methods

  async createClient(client: createOAuthClient) {
    const newClient = { ...client };
    const newSecret = await bcrypt.hash(client.secret, 10);
    newClient.secret = newSecret;
    const createdUser = await this.oauthClient.create(newClient);
    return await createdUser.save();
  }

  async getClient(_id: string): Promise<OAuthClient> {
    const client = await this.oauthClient.findOne({ _id });
    if (!client) throw new NotFoundException('Client not found');
    return client;
  }

  async validateClient(_id: string, secret: string): Promise<OAuthClient> {
    const client = await this.getClient(_id);
    const isValid = await bcrypt.compare(secret, client.secret);
    if (!isValid) throw new UnauthorizedClientError('Wrong credentials');
    return client;
  }

  async getUserFromCode(auth_code: string) {
    const code = await this.oauthAuthorizationCode.findOne({
      authorization_code: auth_code,
    });
    const user = await this.getUserInfo(code.user_id);
    const scope = code.scope;
    return { user, scope };
  }

  async getUserFromToken(token: string): Promise<OAuthUser | null> {
    const decodedToken = this.jwtService.decode(token) as tokenPayload;
    const user = await this.getUserInfo(decodedToken.sub);
    if (!user || user === null) {
      throw new UnauthorizedException('User not found');
    }
    return user;
  }

  async getUserFromUserToken(token: string): Promise<OAuthUser | null> {
    const decodedToken = this.jwtService.decode(token) as userToken;
    const user = await this.getUserInfo(decodedToken.id);
    if (!user || user === null) {
      throw new UnauthorizedException('User not found');
    }
    return user;
  }

  async getUserInfo(user_id: string): Promise<userInfo | null | any> {
    const response = await axios({
      method: 'get',
      url: `${this.apiCoreURL()}/patients/${user_id}`,
    });
    const user = response.data as patient;
    const user_info = {
      user_id: user._id,
      email: user.email,
      first_name: user.firstName,
      last_name: user.lastName,
      gender: user.gender,
      birth_date: user.birthDay,
    };
    return user_info;
  }

  async validateScope(ReqScope): Promise<scopes> {
    if (!ReqScope) throw new BadRequestException('please verify the scopes');
    const request = ReqScope;
    let result;
    if (Object.values(scopes).includes(request as scopes)) {
      result = request;
    } else {
      throw new UnauthorizedException('scope');
    }
    return result;
  }

  async generateAccessToken(
    client: OAuthClient,
    user: OAuthUser,
    scope: scopes,
    authorization_code: string,
  ) {
    const authCode = await this.getAuthorizationCode(authorization_code);
    if (!authCode) throw new UnauthorizedException();
    const tokenPayload: tokenPayload = {
      sub: user.user_id,
      scope: scope,
      client_id: client.id,
      iat: this.getUT(),
      exp: this.getUT() + this.accessTokenExpTime,
    };
    const tokenIdPayload = {
      iss: 'https://www.happlabs.com',
      sub: user.user_id,
      aud: client.id,
      exp: this.getUT() + this.authCodeExpTime,
      iat: this.getUT(),
    };
    const newToken = this.jwtService.sign(tokenPayload);
    const newIdToken = this.jwtService.sign(tokenIdPayload);
    const response = {
      access_token: newToken,
      token_type: 'Bearer',
      expires_in: tokenPayload.exp - this.getUT(),
      id_token: newIdToken,
    };
    return response;
  }

  async saveToken(
    token,
    client: OAuthClient,
    user: OAuthUser,
    scope: scopes,
    authCode: string,
  ) {
    if (!token || !client || !user || !scope) {
      throw new BadRequestException('Please, check your payload');
    }
    const alreadyExist = await this.oauthToken.findOne({ sub: user.id });
    if (alreadyExist) {
      this.revokeAcessToken(alreadyExist.access_token);
    }
    const authCodeId = await this.getAuthorizationCode(authCode);
    const createdToken = await new this.oauthToken({
      access_token: token.access_token,
      expires_at: this.getUT() + this.accessTokenExpTime,
      client_id: client.id,
      sub: user.id,
      scope: scope,
      originatingAuthCodeId: authCodeId.id,
    });
    return await createdToken.save();
  }

  async getAccessToken(accessToken: string): Promise<OAuthToken> {
    const token = await this.oauthToken.findOne({
      access_token: accessToken,
    });
    if (!token || token == null) throw new NotFoundException('Token not found');
    return token;
  }

  async revokeAcessToken(accessToken: string): Promise<OAuthToken | null> {
    const token = await this.getAccessToken(accessToken);
    return token.delete();
  }

  async validateToken(access_token: string): Promise<string> | null {
    try {
      await this.jwtService.verify(access_token, {
        maxAge: this.accessTokenExpTime,
        secret: process.env.JWT_SECRET,
      });
    } catch {
      return null;
    }
    return access_token;
  }

  async validateURI(
    client: OAuthClient,
    redirect_uri: string,
  ): Promise<boolean> {
    const allowed_uris = client.redirectUris;
    const isAllowed = await allowed_uris.some((uri) => uri == redirect_uri);
    if (isAllowed) {
      return true;
    }
    throw new UnauthorizedException('redirect uri mismatch');
  }

  async validateAuthorizationRequest(
    client_id: string,
    redirect_uri: string,
    scope: string,
  ) {
    const client = await this.getClient(client_id);
    const accepted_uris = client.redirectUris as Array<string>;
    const accepted_scope = await this.validateScope(scope);
    const clientScopes = client.scopes;
    if (
      !accepted_uris.some((uri) => uri === redirect_uri) ||
      !clientScopes.some((scope) => scope == accepted_scope)
    ) {
      throw new UnauthorizedRequestError('redirect_uri or scope mismatch');
    }
    return client;
  }

  async generateAuthorizationCode(
    client: OAuthClient,
    user: OAuthUser,
    scope: string,
    redirect_uri: string,
  ) {
    const length = 32;
    const charset =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let code = '';
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * charset.length);
      code += charset.charAt(randomIndex);
    }
    const authorizationCodePayload = {
      authorization_code: code,
      expires_at: this.getUT() + this.authCodeExpTime,
      redirect_uri: redirect_uri,
      scope: scope,
      client_id: client.id,
      user_id: user.user_id,
    };
    await this.saveAuthorizationCode(authorizationCodePayload);
    return authorizationCodePayload.authorization_code;
  }

  async saveAuthorizationCode(authorization_code) {
    const alreadyExist = await this.oauthAuthorizationCode.findOne({
      user_id: authorization_code.user_id,
    });
    if (alreadyExist) {
      await this.revokeAuthorizationCode(alreadyExist.authorization_code);
    }
    const createAuthCode = await new this.oauthAuthorizationCode(
      authorization_code,
    );
    await createAuthCode.save();
    return createAuthCode;
  }

  async getAuthorizationCode(
    authorization_code: string,
  ): Promise<OAuthAuthorizationCode | null> {
    const authCode = await this.oauthAuthorizationCode.findOne({
      authorization_code,
    });
    if (!authCode) throw new NotFoundException();
    return authCode;
  }

  async revokeAuthorizationCode(authorization_code: string) {
    const authCode = await this.getAuthorizationCode(authorization_code);
    return authCode.delete();
  }

  async isAuthorized(user: OAuthUser, payload: any) {
    const isAuthorized = await this.oauthAuthorizationCode.findOne({
      user_id: user.user_id,
    });
    if (!isAuthorized || isAuthorized.expires_at < this.getUT()) {
      return {
        statusCode: 204,
      };
    } else {
      if (
        isAuthorized.scope === payload.scope &&
        isAuthorized.redirect_uri === payload.redirectUri
      ) {
        return {
          url: `${payload.redirectUri}?code=${isAuthorized.authorization_code}`,
          statusCode: 200,
        };
      }
    }
    return { statusCode: 204 };
  }
}
