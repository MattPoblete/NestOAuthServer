import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { SCOPES } from '../decorators/scope-protected.decorator';
import { scopes, tokenPayload } from '../interfaces';

@Injectable()
export class scopeGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const isPublic = this.reflector.get('isPublic', context.getHandler());
    if (isPublic) {
      return true;
    }
    const validScopes = this.reflector.get<scopes[]>(
      SCOPES,
      context.getHandler(),
    );
    const req = context.switchToHttp().getRequest();
    const client = req.user as tokenPayload;
    const isValid = validScopes.some((scope) => scope === client.scope);
    if (!isValid)
      throw new ForbiddenException('User does not have a valid scope');
    return true;
  }
}
