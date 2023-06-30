import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class OAuthToken extends Document {
  @Prop()
  access_token: string;
  @Prop()
  expires_at: number;
  @Prop({ unique: false })
  client_id?: string;
  @Prop({ unique: false })
  sub?: string | null;
  @Prop()
  scope: string;
  @Prop()
  originatingAuthCodeId?: string | null;
}

export const OAuthTokenSchema = SchemaFactory.createForClass(OAuthToken);
