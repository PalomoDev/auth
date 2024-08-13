// auth/roles.guard.ts
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UserRole } from '../user/user.schema';

/**
 * @class RolesGuard
 * @description
 * Этот guard предназначен для ограничения доступа к определённым ресурсам в зависимости от роли пользователя.
 * Он проверяет, соответствует ли роль пользователя одной из требуемых ролей, указанных в метаданных маршрута или контроллера.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  /**
   * @method canActivate
   * @description
   * Метод проверяет, имеет ли пользователь необходимые роли для доступа к ресурсу.
   * Если роли не указаны, доступ предоставляется по умолчанию.
   * @param context ExecutionContext - контекст выполнения, содержащий информацию о текущем запросе и контроллере.
   * @returns boolean - Возвращает true, если пользователь имеет соответствующую роль, иначе false.
   */
  canActivate(context: ExecutionContext): boolean {
    // Извлечение необходимых ролей из метаданных, прикрепленных к текущему обработчику или контроллеру
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(
      'roles',
      [context.getHandler(), context.getClass()],
    );

    // Если роли не определены, доступ разрешен по умолчанию
    if (!requiredRoles) {
      return true;
    }

    // Извлечение пользователя из текущего запроса
    const { user } = context.switchToHttp().getRequest();

    // Проверка, соответствует ли роль пользователя одной из требуемых ролей
    return requiredRoles.some((role) => user.role === role);
  }
}
