import supertest from 'supertest';
import { app } from '../app.js';

describe('Test the healthcheck path', () => {
  test('It should response the 200 status code', async () => {
    const response = await supertest(app).get('/healthcheck');
    expect(response.statusCode).toBe(200);
  });
});

describe('Test the existing path', () => {
  test('It should response the 200 status code', async () => {
    const response = await supertest(app).get('/promo_data');
    expect(response.statusCode).toBe(200);
  });
});

describe('Test the non-existent path', () => {
  test('It should response the 404 status code', async () => {
    const response = await supertest(app).get('/random_words_endpoint');
    expect(response.statusCode).toBe(404);
  });
});

describe('Test the authorization routine', () => {
  test('It should response the 401 status code', async () => {
    const response = await supertest(app).get('/list_access_logs');
    expect(response.statusCode).toBe(401);
  });
});

describe('Test the authorization endpoint #1', () => {
  test('It should not authorize the user', async () => {
    const payload = { email: 'admin@dash.org', pass: 'wrong_password' };
    const response = await supertest(app)
      .post('/login')
      .send(payload)
      .set('Content-Type', 'application/json')
      .set('Accept', 'application/json');
    expect(response.statusCode).toBe(404);
  });
});

describe('Test the authorization endpoint #2', () => {
  test('It should response the 200 status code', async () => {
    const payload = { email: 'admin@dash.org', pass: 'dashdashdash' };
    const response = await supertest(app)
      .post('/login')
      .send(payload)
      .set('Content-Type', 'application/json')
      .set('Accept', 'application/json');
    expect(response.statusCode).toBe(200);
  });
});

describe('Test the authorization token', () => {
  test('It should response the 200 status code', async () => {
    const payload = { email: 'admin@dash.org', pass: 'dashdashdash' };
    let token = await supertest(app)
      .post('/login')
      .send(payload)
      .set('Content-Type', 'application/json')
      .set('Accept', 'application/json');
    const response = await supertest(app)
      .get('/list_access_logs')
      .set('Authorization', `Bearer ${token.body.data}`);
    expect(response.statusCode).toBe(200);
  });
});