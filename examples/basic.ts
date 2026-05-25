import { AuthzX } from "../src/index";

async function main() {
  const authzx = new AuthzX({ apiKey: "azx_your_api_key_here" });

  const allowed = await authzx.check(
    { id: "user-123" },
    "read",
    { id: "doc-456" }
  );
  console.log("Allowed:", allowed);

  const resp = await authzx.authorize({
    subject: { id: "user-123" },
    resource: { id: "doc-456" },
    action: { name: "read" },
  });
  console.log(`Decision=${resp.decision} Reason="${resp.context?.reason}" Path=${resp.context?.access_path}`);
}

main().catch(console.error);
