import { Controller, Body, Post, UseGuards, Request, Res, HttpStatus, NotFoundException, Inject, forwardRef, BadRequestException } from '@nestjs/common';
import { ApiUseTags, ApiBearerAuth, ApiOkResponse, ApiBadRequestResponse, ApiUnauthorizedResponse } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { Response } from 'express';
import { UsersService } from '../../shared/services';
import { AuthService } from '.';
import { ForgotPasswordPayload } from '../../shared/dto/forgot-password.payload';
import { LoginPayload } from '../../shared/dto/login.payload';
import { RegisterPayload } from '../../shared/dto/register.payload';

@Controller('auth')
@ApiUseTags('Authentication')
export class AuthController {
	constructor(
		private readonly authService: AuthService,
        @Inject(forwardRef(() => UsersService)) private readonly usersService: UsersService,
	) { }

	@Post('login')
	@ApiOkResponse({ description: 'Successfully authenticated' })
	@ApiBadRequestResponse({ description: 'Bad Request' })
	async login(@Body() payload: LoginPayload, @Res() res: Response): Promise<any> {
		return await this.authService.validateUser(payload).then(user => {
			if (!user) {
				return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
                    message: 'User Not Found',
                });
			} else {
				const token = this.authService.createToken(user);
				return res.status(HttpStatus.OK).json(Object.assign(token, { user : user }));
			}
		});
	}

	@Post('register')
	@ApiOkResponse({ description: 'Successfully registered' })
	@ApiBadRequestResponse({ description: 'Bad Request' })
	async register(@Body() payload: RegisterPayload, @Res() res: Response): Promise<any> {
		try {
			return await this.usersService.create(payload).then(user => {
				if (!user) {
					return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
						message: 'Something went wrong during register, please try again later',
					});
				} else {
					// const token = this.authService.createToken(user);
					// return res.status(HttpStatus.OK).json(Object.assign(token, { user : user }));
					return res.status(HttpStatus.OK).json({
						status: 200,
						data: user
					});
				}
			});
		} catch(error) {
            throw new BadRequestException(error);
		}
	}

	@ApiBearerAuth()
	@Post('logout')
	@UseGuards(AuthGuard('jwt'))
	@ApiOkResponse({ description: 'Successful response' })
	@ApiUnauthorizedResponse({ description: 'Unauthorized' })
	@ApiBadRequestResponse({ description: 'Bad Request' })
	async logout(@Request() request: any, @Res() res: Response): Promise<any> {
		try {
			return await this.authService.logout(request).then(() => {
				return res.status(HttpStatus.OK).json({
					status: 200,
					message: "Successfully logged out"
				});
			});			
		} catch(error) {
            throw new BadRequestException(error);
		}
	}

	@ApiBearerAuth()
	@Post('refresh-token')
	@ApiOkResponse({ description: 'Successful response' })
	@ApiBadRequestResponse({ description: 'Bad Request' })
	async refreshToken(@Body() payload: any, @Res() res: Response): Promise<any> {
		if (!payload.token) {
			throw new NotFoundException('No token provided.');
		}

		let token = await this.authService.refreshToken(payload);
		return res.status(HttpStatus.OK).json(Object.assign({}, token));
	}

	@Post('password/email')
	@ApiOkResponse({ description: 'Successfully authenticated' })
	@ApiBadRequestResponse({ description: 'Bad Request' })
	async forgotUserPassword(@Body() payload: ForgotPasswordPayload, @Res() response: Response): Promise<any> {
		try {
			return await this.usersService.sendPasswordEmail(payload.email).then(() => {
				return response.status(HttpStatus.OK).json({
					status: HttpStatus.OK,
					message: 'Check your mail to get new password.'
				}); 
			}).catch((error: any) => {
				throw new BadRequestException(error);
			});
		} catch (error) {
			throw new BadRequestException(error);
		}
	}

	@Post('admin/login')
	@ApiOkResponse({ description: 'Successfully authenticated' })
	@ApiBadRequestResponse({ description: 'Bad Request' })
	async adminLogin(@Body() payload: LoginPayload, @Res() res: Response): Promise<any> {
		return await this.authService.adminLogin(payload).then(user => {
			if (!user) {
				return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
					message: 'User Not Found',
				});
			} else {
				const token = this.authService.createToken(user, {
					expiresIn : '1d'
				});
				return res.status(HttpStatus.OK).json({
					status: HttpStatus.OK,
					data: Object.assign(token, { user: user })
				});
			}
		});
	}

	@Post('admin/forgot-password')
	@ApiOkResponse({ description: 'Successfully authenticated' })
	@ApiBadRequestResponse({ description: 'Bad Request' })
	async adminForgotPassword(@Body() payload: any, @Res() res: Response): Promise<any> {
		return await this.authService.adminForgotPassword(payload).then(async (user: any) => {
			if (!user) {
				return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
					message: 'User Not Found',
				});
			} else {
				return res.status(HttpStatus.OK).json({
					status: HttpStatus.OK,
					message: 'Check your mail to reset your password.'
				});
			}
		});
	}

	@Post('admin/reset-password')
	@ApiOkResponse({ description: 'Successfully authenticated' })
	@ApiBadRequestResponse({ description: 'Bad Request' })
	async adminResetPassword(@Body() payload: any, @Res() res: Response): Promise<any> {
		return await this.authService.adminResetPassword(payload).then(async (user: any) => {
			if (!user) {
				return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
					message: 'User Not Found',
				});
			} else {
				const token = this.authService.createToken(user);
				return res.status(HttpStatus.OK).json({
					status: HttpStatus.OK,
					message: 'Your password updated successfully.',
					data: Object.assign(token, { user: user })
				});
			}
		});
	}

	@Post('verify-token')
	@ApiOkResponse({ description: 'Successfully authenticated' })
	@ApiBadRequestResponse({ description: 'Bad Request' })
	async adminVerifyToken(@Body() payload: any, @Res() res: Response): Promise<any> {
		return await this.authService.verifyToken(payload).then(async (user: any) => {
			if (!user) {
				return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
					message: 'User Not Found',
				});
			} else {
				const token = this.authService.createToken(user);
				return res.status(HttpStatus.OK).json({
					status: HttpStatus.OK,
					message: 'Your password updated successfully.',
					data: Object.assign(token, { user: user })
				});
			}
		});
	}
}
