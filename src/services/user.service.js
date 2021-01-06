const argon2 = require('argon2');
const prisma = require('../db-setup');

class UserService {
	static async findByEmail(email) {
		if (typeof email !== 'string') throw new Error('Argument must be a string');

		return prisma.users.findUnique({ where: { email } });
	}

	static findById(id) {
		return prisma.users.findUnique({ where: { id } });
	}

	static hashPassword(password) {
		return argon2.hash(password);
	}

	static getAuthorizedEmailRecord(email) {
		return prisma.authorizedEmails.findUnique({
			where: { email },
		});
	}

	static async createUser(email, password, role = 'VISITOR') {
		return prisma.users.create({
			data: {
				email,
				password: await UserService.hashPassword(password),
				role,
			},
		});
	}

	static async addAuthorizedEmail(email, role) {
		return await prisma.authorizedEmails.create({
			data: { email, role },
		});
	}
}

module.exports = UserService;
