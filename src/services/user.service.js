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

	static async createUser(email, password, role) {
		return prisma.users.create({
			data: {
				email,
				password: await UserService.hashPassword(password),
				role,
			},
		});
	}

	static async passwordMatch(hash, password) {
		return argon2.verify(hash, password);
	}

	static async updatePassword(email, oldPassword, newPassword) {
		const userRecord = await UserService.findByEmail(email);
		if (!userRecord) throw new Error('User not found');

		if (await UserService.passwordMatch(userRecord.password, oldPassword)) {
			await prisma.users.update({
				where: { email },
				data: { password: await UserService.hashPassword(newPassword) },
			});
		}
	}

	static getAuthorizedEmails() {
		return prisma.authorizedEmails.findMany();
	}

	static addAuthorizedEmail(email, role) {
		return prisma.authorizedEmails.create({
			data: { email, role },
		});
	}

	static deleteAuthorizedEmail(email) {
		return prisma.authorizedEmails.delete({
			where: { email },
		});
	}

	static updateAuthorizedEmailRole(email, role) {
		return prisma.authorizedEmails.update({
			where: { email },
			data: { role },
		});
	}
}

module.exports = UserService;
