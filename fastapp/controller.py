def start_executors():
    from fastapp.models import Base, Executor
    for base in Base.objects.all():
        print base
    #    if len(base.executor.all()) == 0:
    #        executor = Executor(base=base)
    #        executor.save()
    #    else:
    #        executor = base.executor.all()[0]
    #    if not executor.is_running():
    #        executor.start()
