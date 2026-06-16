const request = require('supertest');
const app     = require('./app');
 
describe('Health endpoint', () => {
  it('returns 200 with status ok', async () => {
    const res = await request(app).get('/health');
    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});
 
describe('Calculate endpoint', () => {
  it('evaluates a safe arithmetic expression', async () => {
    const res = await request(app)
      .post('/calculate')
      .send({ expression: '2 + 3' });
    expect(res.statusCode).toBe(200);
    expect(res.body.result).toBe(5);
  });
 
  it('returns 400 for invalid expression', async () => {
    const res = await request(app)
      .post('/calculate')
      .send({ expression: 'undefinedVar' });
    expect(res.statusCode).toBe(400);
  });
});
 
describe('Search endpoint', () => {
  it('returns a query string showing injection risk', async () => {
    const res = await request(app).get('/search?query=admin');
    expect(res.statusCode).toBe(200);
    expect(res.body.query).toContain('admin');
  });
});
 

