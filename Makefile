LIBDIR := lib
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(CLONE_ARGS))
git clone -q --depth 10 $(CLONE_ARGS) --single-branch https://github.com/martinthomson/i-d-template $(LIBDIR)
else
git clone -q --depth 10 --single-branch https://github.com/martinthomson/i-d-template $(LIBDIR)
endif
