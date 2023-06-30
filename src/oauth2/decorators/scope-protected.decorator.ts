import { SetMetadata } from '@nestjs/common';
import { scopes } from '../interfaces';

export const SCOPES = 'scopes';

export const scopeProtected = (...scopes: scopes[]) =>
  SetMetadata(SCOPES, scopes);
