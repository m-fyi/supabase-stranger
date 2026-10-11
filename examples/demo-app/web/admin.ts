// Quick admin tool, "temporary".
import { createClient } from "@supabase/supabase-js";

export const admin = createClient("http://localhost:54399", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwicmVmIjoiZmFrZXByb2plY3QiLCJpc3MiOiJzdXBhYmFzZSJ9.c2lnbmF0dXJlLXRlc3Q");
