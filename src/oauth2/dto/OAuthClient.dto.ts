import { IsString, IsNotEmpty } from 'class-validator';
import { PartialType } from '@nestjs/mapped-types';

import { scopes, allowedGrants } from '../interfaces';

export class createOAuthClient {
  @IsString()
  @IsNotEmpty()
  name: string;
  @IsString()
  secret: string | null;
  //@IsArray()
  @IsNotEmpty()
  redirectUris: string[];
  //@IsArray()
  @IsNotEmpty()
  allowedGrants: allowedGrants[];
  //@IsArray()
  @IsNotEmpty()
  scopes: scopes[];
  @IsNotEmpty()
  tos: string;
  @IsNotEmpty()
  logo: string;
}

export class updateOAuthClient extends PartialType(createOAuthClient) {}
