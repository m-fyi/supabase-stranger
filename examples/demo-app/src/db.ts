import { createClient } from "@supabase/supabase-js";

export const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);

export const myProfile = (id: string) => supabase.from("profiles").select("*").eq("id", id).single();
export const myNotes = () => supabase.from("notes").select("*");
export const inbox = () => supabase.from("messages").select("*");
export const saveLead = (lead: object) => supabase.from("leads").insert(lead);
export const feed = () => supabase.rpc("get_feed");
export const uploadDoc = (path: string, file: Blob) => supabase.storage.from("documents").upload(path, file);
