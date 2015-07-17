<div class="wrapper">
    <p>You are not authorized to access this page, maybe you should login first to access it or you can go back to previous page.</p>
    <div class="row button-form">
        <div class="span-12">
            <div class="row">
                <a href="javascript:history.back()" class="button">Back</a>
                <a href="<?php echo URL::site('/login').'?!continue='.\Bono\Helper\URL::redirect() ?>" class="button">Login</a>
            </div>
        </div>
    </div>
</div>