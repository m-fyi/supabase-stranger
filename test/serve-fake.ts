import { createServer } from "node:http";
import { fakeSupabase, leakyProject } from "./fake-supabase.js";

/** Serves the leaky fake project on localhost, for demos and skill evals. */
const fake = fakeSupabase(leakyProject());
const port = Number(process.env.PORT ?? 54399);

createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const body = chunks.length ? Buffer.concat(chunks) : undefined;
  const headers = Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k, String(v)]));
  try {
    const r = await fake.fetch(`http://localhost:${port}${req.url}`, { method: req.method, headers, body });
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(Buffer.from(await r.arrayBuffer()));
  } catch (e) {
    res.writeHead(405).end(String(e));
  }
}).listen(port, () => console.log(`Leaky demo Supabase on http://localhost:${port}`));
