window.NetterViewAPI = {
  async getJson(url) {
    const response = await fetch(url);
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Request failed.");
    }

    return data;
  },

  async postJson(url, payload) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const text = await response.text();
    let data = {};

    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        throw new Error(`Server returned non-JSON response: ${text}`);
      }
    }

    if (!response.ok) {
      throw new Error(data.error || "Request failed.");
    }

    return data;
  },
};
