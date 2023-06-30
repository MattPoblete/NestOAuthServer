import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { Observable } from 'rxjs';
import { ConfigService } from '@nestjs/config';

import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(private reflector: Reflector, private config: ConfigService) {}
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const api_key = this.config.get('apiKey');
    const isPublic = this.reflector.get(IS_PUBLIC_KEY, context.getHandler());
    if (isPublic) {
      return true;
    }
    const req = context.switchToHttp().getRequest<Request>();
    const authHeader = req.header('Authorization');
    const isAuth = authHeader === api_key;
    if (!isAuth) {
      throw new UnauthorizedException(
        'Invalid API Key: The key provided is not valid. Please ensure you are using a correct key for authentication.',
      );
    }
    return true;
  }
}
