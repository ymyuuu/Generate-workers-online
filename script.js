document.addEventListener("DOMContentLoaded", function() {
	const textarea = document.getElementById("ipInput");
	const generateButton = document.getElementById("generateButton");
	const uuidInput = document.getElementById("uuidInput");
	const ipInput = textarea;
	const jsCodeDisplay = document.getElementById("jsCodeDisplay");
	const resultContainer = document.getElementById('resultContainer');
	const copyButton = document.getElementById("copyButton");

	const defaultProxyIPs = "nine.ymy.gay";
	const workersJsUrl = "worker.js";

	textarea.addEventListener("input", function() {
		this.style.height = "auto";
		this.style.height = this.scrollHeight + "px";
	});

	textarea.dispatchEvent(new Event("input"));

	generateButton.addEventListener("click", async function() {
		let generatedUUID = uuidInput.value.trim();
		if (generatedUUID === "") {
			generatedUUID = generateUUID();
		}

		let proxyIPInputValue = ipInput.value.trim();
		if (proxyIPInputValue === "") {
			proxyIPInputValue = defaultProxyIPs;
		}

		const proxyIPs = extractProxyIPs(proxyIPInputValue);
		const proxyIPsFunction = `const proxyIPs = ${JSON.stringify(proxyIPs)};`;

		const jsCode = await fetchJavaScriptCode();
		const updatedJsCode = replaceCodeInJs(jsCode, generatedUUID, proxyIPsFunction);

		jsCodeDisplay.innerText = updatedJsCode;

		uuidInput.value = "";
		ipInput.value = "";
		ipInput.dispatchEvent(new Event("input"));
		resultContainer.style.display = "block";
	});

	copyButton.addEventListener("click", function() {
		copyToClipboard(jsCodeDisplay.innerText);
	});

	function copyToClipboard(text) {
		const tempInput = document.createElement("textarea");
		tempInput.value = text;
		document.body.appendChild(tempInput);
		tempInput.select();
		document.execCommand("copy");
		document.body.removeChild(tempInput);
	}

	function generateUUID() {
		return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function(c) {
			const r = Math.random() * 16 | 0,
				v = c == "x" ? r : (r & 0x3 | 0x8);
			return v.toString(16);
		});
	}

	function extractProxyIPs(ipInputValue) {
		const ips = ipInputValue.match(/(\d+\.\d+\.\d+\.\d+|[\w.-]+\.\w{2,20})/g) || [];
		return ips;
	}

	async function fetchJavaScriptCode() {
		const response = await fetch(workersJsUrl);
		const jsCode = await response.text();
		return jsCode;
	}

	function replaceCodeInJs(jsCode, generatedUUID, proxyIPsFunction) {
		const updatedCode = jsCode.replace(/let userID = 'uuid';/, `let userID = '${generatedUUID}';`);
		return updatedCode.replace(/const proxyIPs = .+?;/, proxyIPsFunction);
	}
});
