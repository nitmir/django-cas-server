function createCookie(name, value, days){
    var expires;
    var date;
    if(days){
        date = new Date();
        date.setTime(date.getTime()+(days*24*60*60*1000));
        expires = "; expires="+date.toGMTString();
    }
    else{
        expires = "";
    }
    document.cookie = name + "=" + value + expires + "; path=/";
}

function readCookie(name){
    var nameEQ = name + "=";
    var ca = document.cookie.split(";");
    for(var i=0;i < ca.length;i++) {
        var c = ca[i];
        while (c.charAt(0) === " "){
            c = c.substring(1,c.length);
        }
        if (c.indexOf(nameEQ) === 0){
            return c.substring(nameEQ.length,c.length);
        }
    }
    return null;
}

function eraseCookie(name) {
    createCookie(name,"",-1);
}

function discard_and_remember(id, cookie_name, token, days=10*365){
    jQuery(function( $ ){
        $(id).click(function( e ){
            e.preventDefault();
            createCookie(cookie_name, token, days);
        });
        if(readCookie(cookie_name) === token){
            $(id).parent().hide();
        }
    });
}
