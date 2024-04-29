import 'dotenv/config';
import { app } from './app.js';

app.listen(process.env.DEVEL_PORT, () => console.log(`Server running at http://localhost:${process.env.DEVEL_PORT}`));