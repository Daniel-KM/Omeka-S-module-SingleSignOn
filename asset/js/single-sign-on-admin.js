$(document).ready(function() {

    /**
     * Add buttons "add" at the end of fhe form.
     */
    const buttonAdd = '<button type="button" class="add-idp">+ IdP</button>';
    $('#singlesignon_idps').append(buttonAdd);

    /**
     * Add buttons "remove" to each fieldset.
     */
    const buttonRemove = '<button type="button" class="remove-idp">- IdP</button>';
    $('#singlesignon_idps fieldset.singlesignon-idp').append(buttonRemove);
    if ($('#singlesignon_idps fieldset.singlesignon-idp').length <= 1) {
        $('.remove-idp').hide();
    }

    /**
     * Store the index to manage adding/removing.
     */
    $('#singlesignon_idps').data('total-idp', $('#singlesignon_idps fieldset.singlesignon-idp').length);

    /**
     * Handle add fieldset.
     */
    $('#singlesignon_idps').on('click', '.add-idp', function() {
        const newTotal = $('#singlesignon_idps').data('total-idp') + 1;
        $('#singlesignon_idps').data('total-idp', newTotal);
        var template = $('#singlesignon_idps > span[data-template]').data('template');
        template = template.replace(/__index__/g, newTotal);
        template = template.substring(0, template.length - 11) + buttonRemove + '</fieldset>';
        $('#singlesignon_idps fieldset.singlesignon-idp').last().after(template);
        $('.remove-idp').show();
    });

    /**
     * Handle remove fieldset.
     */
    $('#singlesignon_idps').on('click', '.remove-idp', function() {
        const currentCount = $('#singlesignon_idps fieldset.singlesignon-idp').length;
        if (currentCount <= 1) {
            $('.remove-idp').hide();
            return;
        }
        $(this).closest('fieldset.singlesignon-idp').remove();
        if (currentCount <= 2) {
            $('.remove-idp').hide();
        }
    });

});
