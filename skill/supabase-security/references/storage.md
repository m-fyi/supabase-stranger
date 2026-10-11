# Storage findings

Sections: anon-list, cross-user, public-bucket.

## anon-list
A SELECT policy on `storage.objects` lets strangers list the bucket, so every file name is discoverable. Downloading a public file by URL does not need a SELECT policy; only listing does.

Fix: drop the broad policy, then allow listing only inside the user's own folder.
```sql
create policy "b: owner lists" on storage.objects for select to authenticated
  using (bucket_id = 'b' and (storage.foldername(name))[1] = (select auth.uid())::text);
```
This assumes files are stored as `<user id>/<file>`. If they are not, change the upload path first.

## cross-user
User A listed the folder named after user B's id. The policy checks the bucket but not the folder. Use the policy above. Add the same folder check to insert/update/delete policies, or users can overwrite each other's files.

## public-bucket
Public buckets serve any file to anyone with its path. Right for avatars and product images. Wrong for documents, IDs, invoices or private photos: make the bucket private and hand out short-lived signed URLs (`createSignedUrl`).
