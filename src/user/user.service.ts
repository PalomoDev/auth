import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserRole } from './user.schema';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  // Создание нового пользователя
  async create(email: string, password: string, role: UserRole = UserRole.USER): Promise<User> {
    // Хешируем пароль перед сохранением
    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = new this.userModel({ email, passwordHash, role });
    return newUser.save();
  }

  // Поиск пользователя по email
  async findByEmail(email: string): Promise<User | null> {
    return this.userModel.findOne({ email }).exec();
  }

  // Установка токена для сброса пароля
  async setResetPasswordToken(userId: unknown, token: string, expires: Date): Promise<void> {
    await this.userModel.updateOne(
      { _id: userId },
      { resetPasswordToken: token, resetPasswordExpires: expires }
    );
  }

  // Сброс пароля пользователя
  async resetPassword(userId: unknown, newPassword: string): Promise<void> {
    const passwordHash = await bcrypt.hash(newPassword, 10);
    await this.userModel.updateOne(
      { _id: userId },
      { passwordHash, resetPasswordToken: null, resetPasswordExpires: null }
    );
  }

  // Повышение пользователя до роли админа
  async promoteToAdmin(userId: string): Promise<void> {
    await this.userModel.updateOne({ _id: userId }, { role: UserRole.ADMIN });
  }

  // Установка роли суперадмина
  async setSuperAdminRole(email: string): Promise<void> {
    await this.userModel.updateOne({ email }, { role: UserRole.SUPER_ADMIN });
  }
  async findById(id: string): Promise<User | null> {
    return this.userModel.findById(id).exec();
  }
}