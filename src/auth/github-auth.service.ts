import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes } from 'crypto';

export type GithubProfile = {
  githubId: string;
  email: string;
  name: string;
  avatarUrl?: string;
};

type GithubTokenResponse = {
  access_token?: string;
  error?: string;
};

type GithubUserResponse = {
  id: number;
  login: string;
  name: string | null;
  email: string | null;
  avatar_url?: string;
};

type GithubEmailResponse = {
  email: string;
  primary: boolean;
  verified: boolean;
};

@Injectable()
export class GithubAuthService {
  constructor(private readonly configService: ConfigService) {}

  generateState(): string {
    return randomBytes(32).toString('hex');
  }

  getAuthorizationUrl(state: string) {
    const clientId = this.configService.getOrThrow<string>('GITHUB_CLIENT_ID');
    const callbackUrl = this.configService.getOrThrow<string>('GITHUB_CALLBACK_URL');

    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: callbackUrl,
      scope: 'read:user user:email',
      state,
    });

    const redirectUrl = `https://github.com/login/oauth/authorize?${params.toString()}`;

    return redirectUrl;
  }

  async exchangeCodeForAccessToken(code: string): Promise<string> {
    const clientId = this.configService.getOrThrow<string>('GITHUB_CLIENT_ID');
    const clientSecret = this.configService.getOrThrow<string>('GITHUB_CLIENT_SECRET');
    const callbackUrl = this.configService.getOrThrow<string>('GITHUB_CALLBACK_URL');

    const response = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: callbackUrl,
      }).toString(),
    });

    if (!response.ok) {
      throw new Error('Failed to exchange code for access token');
    }

    const data = (await response.json()) as GithubTokenResponse;

    if (!data.access_token) {
      throw new Error('Github token response missing access_token');
    }

    return data.access_token;
  }

  async fetchProfile(githubAccessToken: string): Promise<GithubProfile> {
    const userResponse = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${githubAccessToken}` },
    });

    if (!userResponse.ok) {
      throw new Error('Failed to fetch Github user profile');
    }

    const user = (await userResponse.json()) as GithubUserResponse;

    let email = user.email;

    if (!email) {
      email = (await this.fetchVerifiedPrimaryEmail(githubAccessToken)) as string;
    }

    if (!email) {
      throw new Error('Github account has no verified email address');
    }

    return {
      githubId: String(user.id),
      email,
      name: user.name ?? user.login,
      avatarUrl: user.avatar_url,
    };
  }

  private async fetchVerifiedPrimaryEmail(
    githubAccessToken: string,
  ): Promise<string | null | undefined> {
    const response = await fetch('https://api.github.com/user/emails', {
      headers: {
        Authorization: `Bearer ${githubAccessToken}`,
        Accept: 'application/vnd.github+json',
      },
    });

    if (!response.ok) {
      throw new Error('Failed to fetch Github user emails');
    }

    const emails = (await response.json()) as GithubEmailResponse[];

    const primaryVerified = emails.find((e) => e.primary && e.verified);

    if (primaryVerified) {
      return primaryVerified.email;
    }

    const anyVerified = emails.find((e) => e.verified);
    return anyVerified?.email;
  }
}
