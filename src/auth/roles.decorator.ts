// auth/roles.decorator.ts
import { SetMetadata } from '@nestjs/common';
import { UserRole } from '../user/user.schema';

// Декоратор для установки требуемых ролей на эндпоинты
export const Roles = (...roles: UserRole[]) => SetMetadata('roles', roles);