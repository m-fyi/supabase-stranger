import type { Client, Identity } from "./http.js";
import type { SourceRefs } from "./source.js";

export type TableInfo = { columns: string[]; uuidColumns: string[] };

export type Schema = {
  tables: Map<string, TableInfo>;
  /** Functions the public key can call, when the API schema says so. */
  rpcs: string[];
  /** Where the table list came from. "openapi" means the API told us everything. */
  source: ("openapi" | "graphql" | "code")[];
};

type OpenApi = {
  paths?: Record<string, unknown>;
  definitions?: Record<string, { properties?: Record<string, { format?: string }> }>;
};

/**
 * Builds the list of tables to test, the way an outsider would: the REST
 * API's own schema if it is public, then GraphQL introspection, then every
 * table name the app's code mentions.
 */
export async function discover(client: Client, anon: Identity, refs?: SourceRefs): Promise<Schema> {
  const schema: Schema = { tables: new Map(), rpcs: [], source: [] };

  const api = await client.get("/rest/v1/", anon, { Accept: "application/openapi+json" }).catch(() => null);
  const spec = api?.status === 200 ? (api.body as OpenApi) : null;
  if (spec?.paths) {
    schema.source.push("openapi");
    for (const path of Object.keys(spec.paths)) {
      if (path.startsWith("/rpc/")) schema.rpcs.push(path.slice(5));
      else if (path !== "/") {
        const name = path.slice(1);
        const props = spec.definitions?.[name]?.properties ?? {};
        schema.tables.set(name, {
          columns: Object.keys(props),
          uuidColumns: Object.entries(props).filter(([, p]) => p.format === "uuid").map(([k]) => k),
        });
      }
    }
  }

  const gql = await client
    .post("/graphql/v1", anon, { query: "{__schema{queryType{fields{name}}}}" })
    .catch(() => null);
  const fields = (gql?.body as { data?: { __schema?: { queryType?: { fields?: { name: string }[] } } } } | null)?.data?.__schema?.queryType
    ?.fields;
  if (fields?.length) {
    let added = 0;
    for (const f of fields) {
      if (!f.name.endsWith("Collection")) continue;
      const name = f.name.slice(0, -"Collection".length);
      if (!schema.tables.has(name)) {
        schema.tables.set(name, { columns: [], uuidColumns: [] });
        added++;
      }
    }
    if (added || !schema.source.length) schema.source.push("graphql");
  }

  if (refs) {
    let added = 0;
    for (const name of refs.tables) {
      if (!schema.tables.has(name)) {
        schema.tables.set(name, { columns: [], uuidColumns: [] });
        added++;
      }
    }
    if (added) schema.source.push("code");
  }

  return schema;
}
