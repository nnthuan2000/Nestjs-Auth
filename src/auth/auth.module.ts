import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UsersModule } from 'src/users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { AccessTokenGuard } from './guards/access-token.guard';
import { GoogleAuthService } from './google-auth.service';
import { GithubAuthService } from './github-auth.service';

@Module({
  imports: [UsersModule, JwtModule.register({})],
  controllers: [AuthController],
  providers: [AuthService, AccessTokenGuard, GoogleAuthService, GithubAuthService],
})
export class AuthModule {}
