import { ExtractJwt, Strategy, JwtPayload } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException, forwardRef, Inject } from '@nestjs/common';

import { ConfigService } from '../config';
import { UsersService } from '../../shared/services';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
	constructor(
		@Inject(forwardRef(() => ConfigService)) private readonly configService: ConfigService,
        @Inject(forwardRef(() => UsersService)) private readonly usersService: UsersService,
	) {
		super({
			jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
			secretOrKey: configService.get('JWT_SECRET_KEY'),
		});
	}

	async validate(payload: JwtPayload, done: any) {
		let { exp, iat, id, email } = payload;
		const timeDiff = exp - iat;
		if (timeDiff <= 0) {
			throw new UnauthorizedException();
		}
		
		const user = await this.usersService.findOne({
			id : id,
			email : email
		});

		if (!user) {
			throw new UnauthorizedException();
		}

		delete user.password;
		done(null, user);
	}
}
