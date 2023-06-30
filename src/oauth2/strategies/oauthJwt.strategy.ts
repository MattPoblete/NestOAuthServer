import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { tokenPayload } from '../interfaces';

@Injectable()
export class OAuthJwtStrategy extends PassportStrategy(Strategy, 'OAuthJwt') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET,
    });
  }

  async validate(payload: tokenPayload) {
    return payload;
  }
}
