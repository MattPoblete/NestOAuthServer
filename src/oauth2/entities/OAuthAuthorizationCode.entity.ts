import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { scopes } from '../interfaces';

@Schema({ timestamps: true })
export class OAuthAuthorizationCode extends Document {
  @Prop()
  authorization_code: string;
  @Prop()
  expires_at: number;
  @Prop()
  redirect_uri: string;
  @Prop()
  scope: scopes;
  @Prop()
  client_id: string;
  @Prop()
  user_id: string;
}
export const OAuthAuthorizationCodeSchema = SchemaFactory.createForClass(
  OAuthAuthorizationCode,
);
