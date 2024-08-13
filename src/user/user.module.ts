
import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { UserService } from './user.service';
import { User, UserSchema } from './user.schema';

@Module({
  imports: [
    // Регистрируем схему пользователя в MongoDB
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
  ],
  providers: [UserService],
  exports: [UserService], // Экспортируем UserService, чтобы он был доступен в других модулях
})
export class UserModule {}