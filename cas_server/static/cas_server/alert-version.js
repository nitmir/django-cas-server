function alert_version(last_version){
    jQuery(function( $ ){
        $("#alert-version").click(function( e ){
            e.preventDefault();
            var date = new Date();
            date.setTime(date.getTime()+(10*365*24*60*60*1000));
            var expires = "; expires="+date.toGMTString();
            document.cookie = "cas-alert-version=" + last_version + expires + "; path=/";
        });

        var nameEQ="cas-alert-version=";
        var ca = document.cookie.split(";");
        var value;
        for(var i=0;i < ca.length;i++) {
            var c = ca[i];
            while(c.charAt(0) === " "){
                c = c.substring(1,c.length);
            }
            if(c.indexOf(nameEQ) === 0){
                value = c.substring(nameEQ.length,c.length);
            }
        }
        if(value === last_version){
            $("#alert-version").parent().hide();
        }
    });
}
