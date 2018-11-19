<script src="<%=basePath%>jquery.js"></script>
<script src="<%=basePath%>aes.js"></script>
<script src="<%=basePath%>/mode-ecb-min.js"></script>


var key  = CryptoJS.enc.Utf8.parse('o7H8uIM2O5qv65l2');

//前端加密 AES
function Encrypt(word){  
    var srcs = CryptoJS.enc.Utf8.parse(word);  
    var encrypted = CryptoJS.AES.encrypt(srcs, key, {mode:CryptoJS.mode.ECB,padding: CryptoJS.pad.Pkcs7});  
    return encrypted.toString();  
	// return encrypted.toString().replace(/\+/g,'@'); //+号在后台Action无法识别
}  

//解密 AES
function Decrypt(word){  
    var decrypt = CryptoJS.AES.decrypt(word, key, {mode:CryptoJS.mode.ECB,padding: CryptoJS.pad.Pkcs7});  
    return CryptoJS.enc.Utf8.stringify(decrypt).toString();  
}