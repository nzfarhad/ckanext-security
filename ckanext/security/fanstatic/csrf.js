'use strict';

(function ($) {
    // Get CSRF token from meta tag
    var token = $('meta[name="csrf-token"]').attr('content');
    
    if (token) {
        // Add CSRF token to all AJAX requests
        $.ajaxSetup({
            beforeSend: function(xhr) {
                xhr.setRequestHeader('X-CSRF-Token', token);
            }
        });
    }
})(jQuery); 