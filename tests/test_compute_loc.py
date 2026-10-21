from compute_loc import LANG_EXTS, _wanted


def test_production_source_excludes_tests_and_build_outputs():
    assert not _wanted("api/src/test/java/org/example/AuthTest.java", LANG_EXTS["java"])
    assert not _wanted("frontend/src/app/auth.service.spec.ts", LANG_EXTS["typescript"])
    assert not _wanted("tests/test_auth.py", LANG_EXTS["python"])
    assert not _wanted("web/jte-classes/gg/jte/generated/JtePage.java", LANG_EXTS["java"])
    assert not _wanted(".mvn/wrapper/MavenWrapperDownloader.java", LANG_EXTS["java"])
    assert not _wanted("generated-app/.react-router/types/app/+types/root.ts", LANG_EXTS["typescript"])
    assert not _wanted("attacker-app/src/client/attack.js", LANG_EXTS["javascript"])
    assert not _wanted("fineract-command-test/src/main/java/org/example/DummyController.java", LANG_EXTS["java"])


def test_first_party_source_is_not_mistaken_for_dependencies_or_tests():
    assert _wanted("common/src/main/java/org/broadleafcommerce/common/vendor/service/VendorService.java", LANG_EXTS["java"])
    assert _wanted("jeecg-boot/jeecg-cloud-test/src/main/java/org/jeecg/modules/test/seata/Service.java", LANG_EXTS["java"])
    assert _wanted("config/env/all.js", LANG_EXTS["javascript"])
    assert _wanted("server/src/plugins/auth.ts", LANG_EXTS["typescript"])
    assert _wanted("src/main/kotlin/com/example/Portal.kt", LANG_EXTS["java"])
    assert _wanted("jeecg-boot/src/main/java/org/jeecg/modules/test/seata/Service.java", LANG_EXTS["java"])
