const server = require('../../src/server');
const supertest = require('supertest');
const request = supertest(server);

describe('File detected', () => {
	it('works', () => {
		expect(2).toBe(2);
	});
});
