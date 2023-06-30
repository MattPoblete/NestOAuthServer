import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { Oauth2Module } from './oauth2/oauth2.module';
import { EnvConfiguration } from './config/app.config';
import { JoiValidationSchema } from './config/joi.ValidationSchema';

@Module({
  imports: [
    ConfigModule.forRoot({
      load: [EnvConfiguration],
      validationSchema: JoiValidationSchema,
    }),
    MongooseModule.forRoot(process.env.MONGO_DB),
    Oauth2Module,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
