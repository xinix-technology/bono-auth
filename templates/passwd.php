<script type="text/javascript">
    $(".alert p").click(function() {
        $(this).addClass("hide");
    });
</script>

<div class="listing">
    <div class="wrapper">
        <div class="form-input">
            <h4>Change Password</h4>
            <div class="row button-form">
                <div class="span-12">
                    <div class="row">
                        <ul class="flat">
                            <li>
                                <a href="<?php echo URL::base() ?>" class="button">Back</a>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
            <form method="POST">
                <div class="form-input">
                    <div class="row field field-old">
                        <label>Old Password*</label>
                        <input type="password" name="old" placeholder="Input Old Password">
                    </div>
                    <div class="row field field-new">
                        <label>New Password*</label>
                        <input type="password" name="new" placeholder="Input New Password">
                    </div>
                    <div class="row field field-retype">
                        <label>Retype Password</label>
                        <input type="password" name="new_confirmation" placeholder="Confirm New Password">
                    </div>
                    <div class="row button-form">
                        <div class="span-12">
                            <div class="row">
                                <ul class="flat">
                                    <li>
                                        <input type="submit" value="Save">
                                    </li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </form>
        </div>
    </div>
</div>
