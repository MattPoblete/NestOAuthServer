import { Module } from '@nestjs/common';
import { Oauth2Service } from './oauth2.service';
import { Oauth2Controller } from './oauth2.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';

import { OAuthClientSchema } from './entities/OAuthClient.entity';
import { OAuthUserSchema } from './entities/OAuthUser.entity';
import { OAuthTokenSchema } from './entities/OAuthToken.entity';
import { OAuthJwtStrategy } from './strategies/oauthJwt.strategy';
import { OAuthAuthorizationCodeSchema } from './entities/OAuthAuthorizationCode.entity';

@Module({
  imports: [
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
      }),
    }),
    MongooseModule.forFeature([
      {
        name: 'OAuthClient',
        schema: OAuthClientSchema,
      },
      {
        name: 'OAuthUser',
        schema: OAuthUserSchema,
      },
      {
        name: 'OAuthToken',
        schema: OAuthTokenSchema,
      },
      {
        name: 'OAuthAuthorizationCode',
        schema: OAuthAuthorizationCodeSchema,
      },
    ]),
    JwtModule,
    PassportModule,
    ConfigModule,
  ],
  controllers: [Oauth2Controller],
  providers: [Oauth2Service, JwtModule, OAuthJwtStrategy],
})
export class Oauth2Module {}
