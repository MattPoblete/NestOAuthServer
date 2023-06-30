import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class OAuthUser extends Document {
  @Prop()
  user_id: string;
}

export const OAuthUserSchema = SchemaFactory.createForClass(OAuthUser);
