const { Strategy: LocalStrategy } = require('passport-local');
const argon2 = require('argon2');
const UserService = require('../services/user.service');

module.exports = new LocalStrategy(
	{
		usernameField: 'email',
		passwordField: 'password',
	},
	async (email, password, done) => {
		try {
			const user = await UserService.findByEmail(email);

			if (!user || !(await argon2.verify(user.password, password))) {
				return done(null, false);
			}

			return done(null, user);
		} catch (err) {
			return done(err);
		}
	}
);
