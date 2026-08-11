import type { Request, Response } from 'express';
import { AuthResult, AuthService } from './auth.service';
import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { RegisterDto } from './dtos/register.dto';
import { LoginDto } from './dtos/login.dto';
import { RefreshTokenDto } from './dtos/refresh-token.dto';
import { AccessTokenGuard } from './guards/access-token.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import { type JwtPayload } from './types/jwt-payload.type';
import { SafeUser } from 'src/users/users.service';
import { GoogleAuthService } from './google-auth.service';
import { ConfigService } from '@nestjs/config';
import { GithubAuthService } from './github-auth.service';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';

const OAUTH_STATE_COOKIE_NAME = 'google_oauth_state';
const GITHUB_STATE_COOKIE = 'github_oauth_state';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
    private readonly googleAuthService: GoogleAuthService,
    private readonly githubAuthService: GithubAuthService,
  ) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() dto: RegisterDto): Promise<AuthResult> {
    return this.authService.register(dto);
  }

  @Post('login')
  @HttpCode(HttpStatus.CREATED)
  async login(@Body() dto: LoginDto): Promise<AuthResult> {
    return this.authService.login(dto);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.CREATED)
  async refresh(@Body() dto: RefreshTokenDto): Promise<AuthResult> {
    return this.authService.refresh(dto);
  }

  @Post('logout')
  @UseGuards(AccessTokenGuard)
  @HttpCode(HttpStatus.OK)
  async logout(@CurrentUser() user: JwtPayload): Promise<{ success: true }> {
    return this.authService.logout(user.sub);
  }

  @Get('me')
  @UseGuards(AccessTokenGuard)
  @HttpCode(HttpStatus.OK)
  async getProfile(@CurrentUser() user: JwtPayload): Promise<SafeUser> {
    return this.authService.getProfile(user.sub);
  }

  //#region Google OAuth
  @Get('google')
  googleAuth(@Res() res: Response): void {
    const state = this.googleAuthService.generateState();

    res.cookie(OAUTH_STATE_COOKIE_NAME, state, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000,
    });

    const authorizationUrl = this.googleAuthService.getAuthorizationUrl(state);

    res.redirect(authorizationUrl);
  }

  @Get('google/callback')
  async googleCallback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const cookieState = (req.cookies as Record<string, string> | undefined)?.[
      OAUTH_STATE_COOKIE_NAME
    ];

    res.clearCookie(OAUTH_STATE_COOKIE_NAME);

    const frontendUrl = this.configService.getOrThrow<string>('FRONTEND_URL');

    if (!code || !state || !cookieState || state !== cookieState) {
      res.redirect(`${frontendUrl}/auth/callback?error=invalid_oauth_state`);
      return;
    }

    try {
      const googleAccessToken = await this.googleAuthService.exchangeCodeForAccessToken(code);
      const profile = await this.googleAuthService.fetchProfile(googleAccessToken);
      const result = await this.authService.loginWithOAuthProfile({
        email: profile.email,
        name: profile.name,
        avatarUrl: profile.avatarUrl,
        googleId: profile.googleId,
      });

      this.setAuthCookies(res, result.accessToken, result.refreshToken);
      res.redirect(`${frontendUrl}/auth/callback`);
    } catch {
      res.redirect(`${frontendUrl}/auth/callback?error=google_auth_failed`);
    }
  }
  //#endregion

  //#region Github OAuth
  @Get('github')
  githubAuth(@Res() res: Response): void {
    const state = this.githubAuthService.generateState();

    res.cookie(GITHUB_STATE_COOKIE, state, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'lax',
      maxAge: 5 * 60 * 1000,
    });

    const authorizationUrl = this.githubAuthService.getAuthorizationUrl(state);

    res.redirect(authorizationUrl);
  }

  @Get('github/callback')
  async githubCallback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const cookieState = (req.cookies as Record<string, string> | undefined)?.[GITHUB_STATE_COOKIE];

    res.clearCookie(GITHUB_STATE_COOKIE);

    const frontendUrl = this.configService.getOrThrow<string>('FRONTEND_URL');

    if (!code || !state || !cookieState || state !== cookieState) {
      res.redirect(`${frontendUrl}/auth/callback?error=invalid_oauth_state`);
      return;
    }

    try {
      const githubAccessToken = await this.githubAuthService.exchangeCodeForAccessToken(code);
      const profile = await this.githubAuthService.fetchProfile(githubAccessToken);
      const result = await this.authService.loginWithOAuthProfile({
        email: profile.email,
        name: profile.name,
        avatarUrl: profile.avatarUrl,
        githubId: profile.githubId,
      });

      this.setAuthCookies(res, result.accessToken, result.refreshToken);
      res.redirect(`${frontendUrl}/auth/callback`);
    } catch {
      res.redirect(`${frontendUrl}/auth/callback?error=github_auth_failed`);
    }
  }

  //#endregion

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() dto: ForgotPasswordDto): Promise<{ success: true }> {
    return this.authService.forgotPassword(dto);
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() dto: ResetPasswordDto): Promise<{ success: true }> {
    return this.authService.resetPassword(dto);
  }

  private setAuthCookies(res: Response, accessToken: string, refreshToken: string) {
    const isProduction = this.configService.get('NODE_ENV') === 'production';

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000,
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
  }
}
