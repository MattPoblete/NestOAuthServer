import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document, ObjectId } from 'mongoose';
import { Exclude } from 'class-transformer';

@Schema({ timestamps: true })
export class OAuthClient extends Document {
  @Prop({ type: mongoose.Schema.Types.ObjectId, auto: true })
  _id: ObjectId;
  @Prop()
  name: string;
  @Prop()
  @Exclude()
  secret: string | null;
  @Prop()
  redirectUris: [];
  @Prop()
  allowedGrants: [];
  @Prop()
  scopes: [];
  @Prop()
  logo: string;
  @Prop()
  tos: string;
}

export const OAuthClientSchema = SchemaFactory.createForClass(OAuthClient);
