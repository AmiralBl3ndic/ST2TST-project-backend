const server = require('../../src/server');
const prisma = require('../../src/db-setup');
const supertest = require('supertest');
const superSession = require('supertest-session');
const argon2 = require('argon2');
const request = supertest(server);

describe('/auth endpoints', () => {
	let session;

	const meEndpoint = '/auth/me';
	const loginEndpoint = '/auth/login';
	const logoutEndpoint = '/auth/logout';
	const registerEndpoint = '/auth/register';
	const authorizedEmailsEndpoint = '/auth//authorized-emails';

	const defaultAdminCredentials = {
		email: 'st2tst_admin@efrei.net',
		password: 'P4ssword!',
	};

	const resetDb = async () => {
		await prisma.authorizedEmails.deleteMany();
		await prisma.authorizedEmails.create({
			data: {
				email: defaultAdminCredentials.email,
				role: 'ADMIN',
			},
		});
		await prisma.users.deleteMany();
		await prisma.users.create({
			data: {
				email: defaultAdminCredentials.email,
				password: await argon2.hash(defaultAdminCredentials.password),
				role: 'ADMIN',
			},
		});
	};

	const sessionLogin = async (credentials = defaultAdminCredentials) => {
		const sl = await session.post(loginEndpoint).send(credentials);
		expect(sl.status).toBe(200);
	};

	beforeEach(async (done) => {
		await resetDb();
		session = superSession(server);
		done();
	});

	describe('/me', () => {
		it('rejects unauthenticated requests', async (done) => {
			const response = await request.get(meEndpoint);
			expect(response.status).toBe(401);
			done();
		});
	});

	describe('/login', () => {
		it('accepts default ADMIN credentials', async (done) => {
			const response = await request
				.post(loginEndpoint)
				.send(defaultAdminCredentials);

			expect(response.status).toBe(200);
			expect(response.body.message).toBe('Logged in');
			expect(response.body.user.email).toBe(defaultAdminCredentials.email);

			done();
		});
	});

	describe('/logout', () => {
		it('accepts unauthenticated requests', async (done) => {
			const response = await request.get(logoutEndpoint);
			expect(response.status).toBe(200);
			done();
		});

		it('logs someone out when logged in', async (done) => {
			// Log in with default admin credentials
			const loginResponse = await session
				.post(loginEndpoint)
				.send(defaultAdminCredentials);
			expect(loginResponse.status).toBe(200);

			// Logout
			const logoutResponse = await session.get(logoutEndpoint);
			expect(logoutResponse.status).toBe(200);

			done();
		});
	});

	describe('/register', () => {
		[
			{
				it: 'rejects requests with lacking credentials',
				credentials: {},
				tests: (response) => {
					expect(response.status).toBe(400);
					expect(response.body.reason).toBe(
						'Both email and password fields must be defined'
					);
				},
			},
			{
				it: 'rejects requests with lacking password',
				credentials: {
					email: 'valid.email@mail.com',
				},
				tests: (response) => {
					expect(response.status).toBe(400);
					expect(response.body.reason).toBe(
						'Both email and password fields must be defined'
					);
				},
			},
			{
				it: 'rejects requests with lacking email',
				credentials: {
					password: 'friouh6rpzri',
				},
				tests: (response) => {
					expect(response.status).toBe(400);
					expect(response.body.reason).toBe(
						'Both email and password fields must be defined'
					);
				},
			},
			{
				it: 'rejects invalid email address',
				credentials: {
					email: 'qzeproigeotr',
					password: 'friouh6rpzri',
				},
				tests: (response) => {
					expect(response.status).toBe(400);
					expect(response.body.reason).toBe(
						'Invalid email address: qzeproigeotr'
					);
				},
			},
			{
				it: 'rejects already used credentials',
				credentials: defaultAdminCredentials,
				tests: (response) => {
					expect(response.status).toBe(409);
				},
			},
		].forEach((t) => {
			it(t.it, async (done) => {
				const response = await request
					.post(registerEndpoint)
					.send(t.credentials);

				t.tests(response);
				done();
			});
		});

		it('rejects credentials not on the whitelist', async (done) => {
			const credentials = {
				email: 'testuser_@mail.com',
				password: 't3stP4ssw0rd!',
			};

			const response = await request.post(registerEndpoint).send(credentials);
			expect(response.status).toBe(403);

			done();
		});

		it('accepts credentials on the whitelist', async (done) => {
			const credentials = {
				email: 'testuser@mail.com',
				password: 't3stP4ssw0rd!',
				role: 'EMPLOYEE',
			};

			// Insert data into database
			const dbRecord = await prisma.authorizedEmails.create({
				data: {
					email: credentials.email,
					role: credentials.role,
				},
			});
			expect(dbRecord).not.toBeNull();

			const response = await request.post(registerEndpoint).send({
				email: credentials.email,
				password: credentials.password,
			});

			expect(response.status).toBe(201);
			expect(response.body.user.email).toBe(credentials.email);
			expect(response.body.user.role).toBe(credentials.role);

			done();
		});

		it('is possible to log into an account after registration', async (done) => {
			const credentials = {
				email: 'testuser@mail.com',
				password: 't3stP4ssw0rd!',
				role: 'EMPLOYEE',
			};

			// Insert data into database
			const dbRecord = await prisma.authorizedEmails.create({
				data: {
					email: credentials.email,
					role: credentials.role,
				},
			});
			expect(dbRecord).not.toBeNull();

			const registerResponse = await request.post(registerEndpoint).send({
				email: credentials.email,
				password: credentials.password,
			});

			expect(registerResponse.status).toBe(201);
			expect(registerResponse.body.user.email).toBe(credentials.email);
			expect(registerResponse.body.user.role).toBe(credentials.role);

			const loginResponse = await request.post(loginEndpoint).send({
				email: credentials.email,
				password: credentials.password,
			});

			expect(loginResponse.status).toBe(200);
			expect(loginResponse.body.user).toEqual({
				email: credentials.email,
				role: credentials.role,
			});

			done();
		});
	});

	describe('/authorized-emails', () => {
		[('get', 'post')].forEach((method) => {
			it(`does not allow HTTP ${method.toUpperCase()} requests from unauthenticated users`, async (done) => {
				const response = await request[method](authorizedEmailsEndpoint);
				expect(response.status).toBe(401);
				done();
			});
		});

		it('shows the right data to ADMIN users', async (done) => {
			const dbRecords = await prisma.authorizedEmails.findMany();

			await sessionLogin();

			const response = await session.get(authorizedEmailsEndpoint);
			expect(response.status).toBe(200);
			expect(response.body).toEqual(dbRecords);

			done();
		});

		it('rejects invalid roles', async (done) => {
			const dbRecordsBefore = await prisma.authorizedEmails.findMany();
			await sessionLogin();

			const response = await session.post(authorizedEmailsEndpoint).send({
				email: 'something@mail.com',
				role: 'pourztegr',
			});

			expect(response.status).toBe(400);

			const dbRecordsAfter = await prisma.authorizedEmails.findMany();

			expect(dbRecordsBefore).toEqual(dbRecordsAfter);
			done();
		});

		['ADMIN', 'EMPLOYEE'].forEach((role) => {
			it(`enables ADMIN users to create authorized email addresses with ${role} role`, async (done) => {
				const data = { email: 'valid.email@mail.com', role };
				const authorizedBefore = await prisma.authorizedEmails.findMany();

				expect(
					authorizedBefore.map((_) => ({
						email: _.email,
						role: _.role,
					}))
				).not.toContainEqual(data);

				await sessionLogin();
				const response = await session
					.post(authorizedEmailsEndpoint)
					.send(data);

				expect(response.status).toBe(201);
				expect(response.body.authorized).toEqual(data);

				const authorizedAfter = await prisma.authorizedEmails.findMany();

				expect(
					authorizedAfter.map((_) => ({
						email: _.email,
						role: _.role,
					}))
				).toContainEqual(data);

				done();
			});
		});

		describe('/:email', () => {
			['put', 'delete'].forEach((method) => {
				it(`does not allow HTTP ${method.toUpperCase()} requests from unauthenticated users`, async (done) => {
					const response = await request[method](
						authorizedEmailsEndpoint + '/valid.email@mail.com'
					);
					expect(response.status).toBe(401);
					done();
				});
			});

			it('enables ADMIN users to delete authorized email addresses', async (done) => {
				await sessionLogin();

				const recordsBefore = await prisma.authorizedEmails.findMany();

				expect(
					recordsBefore.map((_) => ({
						email: _.email,
						role: _.role,
					}))
				).toContainEqual({
					email: defaultAdminCredentials.email,
					role: 'ADMIN',
				});

				const response = await session.delete(
					`${authorizedEmailsEndpoint}/${defaultAdminCredentials.email}`
				);
				expect(response.status).toBe(204);

				const recordsAfter = await prisma.authorizedEmails.findMany();
				expect(
					recordsAfter.map((_) => ({
						email: _.email,
						role: _.role,
					}))
				).not.toContainEqual({
					email: defaultAdminCredentials.email,
					role: 'ADMIN',
				});
				done();
			});

			it('enables ADMIN users to update roles of authorized email addresses', async (done) => {
				const email = 'future.admin.email@adminmail.com';
				const desiredRole = 'ADMIN';
				await sessionLogin();

				await prisma.authorizedEmails.create({
					data: {
						email,
						role: 'EMPLOYEE',
					},
				});

				const response = await session
					.put(`${authorizedEmailsEndpoint}/${email}`)
					.send({
						role: desiredRole,
					});
				expect(response.status).toBe(204);

				const recordsAfter = await prisma.authorizedEmails.findMany();

				expect(
					recordsAfter.map((_) => ({
						email: _.email,
						role: _.role,
					}))
				).toContainEqual({
					email,
					role: desiredRole,
				});
				done();
			});
		});
	});
});
