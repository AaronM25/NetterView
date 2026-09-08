window.NetterViewDOM = {
  clear(element) {
    element.replaceChildren();
  },

  setText(element, value) {
    element.textContent = value == null || value === "" ? "N/A" : String(value);
  },

  element(tag, options = {}, children = []) {
    const node = document.createElement(tag);

    if (options.className) {
      node.className = options.className;
    }

    if (options.text !== undefined) {
      node.textContent = options.text;
    }

    if (options.attributes) {
      Object.entries(options.attributes).forEach(([key, value]) => {
        node.setAttribute(key, value);
      });
    }

    children.forEach((child) => {
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    });

    return node;
  },
};
