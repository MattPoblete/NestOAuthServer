import { IsString, IsNotEmpty } from 'class-validator';
import { PartialType } from '@nestjs/mapped-types';

export class createToken {
  @IsNotEmpty()
  @IsString()
  grant_type: string;
  @IsNotEmpty()
  @IsString()
  client_id: string;
  @IsNotEmpty()
  @IsString()
  client_secret: string;
  @IsNotEmpty()
  @IsString()
  code: string;
  @IsNotEmpty()
  @IsString()
  redirect_uri: string;
}

export class createTokenInfo extends PartialType(createToken) {}
