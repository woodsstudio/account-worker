export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const OWNER = env.REPO_OWNER || "woodsstudio";
    const REPO = env.REPO_NAME || "account-worker";
    const BRANCH = env.TARGET_BRANCH || "main";
    const GH_TOKEN = env.GITHUB_TOKEN;

    if (!GH_TOKEN) {
      return new Response(JSON.stringify({ error: "Missing GITHUB_TOKEN secret in Cloudflare environment." }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Helper: read file from GitHub repo
    async function ghGetFile(path) {
      const res = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/contents/${path}?ref=${BRANCH}`, {
        headers: {
          "Authorization": `Bearer ${GH_TOKEN}`,
          "User-Agent": "CloverAccount-Worker"
        }
      });
      if (!res.ok) return null;
      const data = await res.json();
      if (!data.content) return null;
      const raw = atob(data.content.replace(/\s/g, ""));
      try {
        return { data: JSON.parse(decodeURIComponent(escape(raw))), sha: data.sha };
      } catch {
        return { data: JSON.parse(raw), sha: data.sha };
      }
    }

    // Helper: commit file to GitHub repo
    async function ghPutFile(path, contentObj, message, existingSha) {
      const contentBase64 = btoa(unescape(encodeURIComponent(JSON.stringify(contentObj, null, 2))));
      const body = {
        message,
        content: contentBase64,
        branch: BRANCH,
        ...(existingSha && { sha: existingSha })
      };

      const res = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/contents/${path}`, {
        method: "PUT",
        headers: {
          "Authorization": `Bearer ${GH_TOKEN}`,
          "User-Agent": "CloverAccount-Worker",
          "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.message || "Failed to commit to GitHub repository");
      }
      return await res.json();
    }

    try {
      // 1. Health check
      if (url.pathname === "/" || url.pathname === "") {
        return new Response(JSON.stringify({
          status: "online",
          service: "Clover Account Gateway",
          endpoints: ["/sync", "/register", "/login"]
        }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // 2. Sync public user details (safe sanitized public payload)
      if (url.pathname === "/sync" && request.method === "GET") {
        const fileInfo = await ghGetFile("accounts.json");
        const accountDb = fileInfo ? fileInfo.data : { users: [] };
        
        // Strip out hashed passwords and sensitive info for public sync
        const publicUsers = (accountDb.users || []).map(u => ({
          id: u.id,
          username: u.username,
          name: u.name,
          createdAt: u.createdAt
        }));

        return new Response(JSON.stringify({ users: publicUsers }), {
          headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "no-cache" }
        });
      }

      // 3. Register Account
      if (url.pathname === "/register" && request.method === "POST") {
        const payload = await request.json();

        if (!payload.email || !payload.username || !payload.passwordHash) {
          return new Response(JSON.stringify({ error: "Missing required registration parameters." }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        const fileInfo = await ghGetFile("accounts.json");
        const accountDb = fileInfo ? fileInfo.data : { version: "1.0.0", users: [] };
        const users = accountDb.users || [];

        // Check if user already exists
        const exists = users.some(u => 
          u.email.toLowerCase() === payload.email.toLowerCase() ||
          u.username.toLowerCase() === payload.username.toLowerCase()
        );

        if (exists) {
          return new Response(JSON.stringify({ error: "Username or email is already registered." }), {
            status: 409,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        const newUser = {
          id: payload.id || `clover_${Date.now()}`,
          name: payload.name || payload.username,
          username: payload.username.toLowerCase(),
          email: payload.email.toLowerCase(),
          passwordHash: payload.passwordHash,
          salt: payload.salt,
          createdAt: new Date().toISOString()
        };

        users.push(newUser);
        accountDb.users = users;
        accountDb.updatedAt = new Date().toISOString();

        await ghPutFile(
          "accounts.json",
          accountDb,
          `Register Clover user: @${newUser.username}`,
          fileInfo ? fileInfo.sha : undefined
        );

        return new Response(JSON.stringify({
          success: true,
          user: {
            id: newUser.id,
            name: newUser.name,
            username: newUser.username,
            email: newUser.email,
            createdAt: newUser.createdAt
          }
        }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // 4. Authenticate / Login
      if (url.pathname === "/login" && request.method === "POST") {
        const { identifier, passwordHash } = await request.json();

        if (!identifier || !passwordHash) {
          return new Response(JSON.stringify({ error: "Missing credentials." }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        const fileInfo = await ghGetFile("accounts.json");
        const accountDb = fileInfo ? fileInfo.data : { users: [] };
        const idLower = identifier.toLowerCase();

        const match = (accountDb.users || []).find(u => 
          (u.email === idLower || u.username === idLower) && u.passwordHash === passwordHash
        );

        if (!match) {
          return new Response(JSON.stringify({ error: "Invalid username/email or password." }), {
            status: 401,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        return new Response(JSON.stringify({
          success: true,
          user: {
            id: match.id,
            name: match.name,
            username: match.username,
            email: match.email,
            createdAt: match.createdAt
          }
        }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      return new Response("Not Found", { status: 404, headers: corsHeaders });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }
  }
};
